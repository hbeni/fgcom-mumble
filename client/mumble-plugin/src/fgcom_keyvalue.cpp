/*******************************************************************//**
 * @file        fgcom_keyvalue.cpp
 * @brief       Defines fgcom_keyvalue class
 * @authors    	Benedikt Hallinger & mill-j
 * @copyright   (C) 2021 under GNU GPL v3 
 *  
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * @todo Move definition into header
 */
 
#ifndef _FGCOM_KEYVALUE__
#define _FGCOM_KEYVALUE__

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>

/**
 * @class fgcom_keyvalue
 * @brief A key and value type storage. Data can be accessed by integer
 * 0 to (getCount() - 2) or string matching key name.
 */

class fgcom_keyvalue{
	private:
		std::vector<std::string> keys;
		std::vector<std::string> values;
	public:
		fgcom_keyvalue();
		
		void add(std::string Key, std::string Value);
		void add(fgcom_keyvalue KeyValue);
        
        int checkSelection(int Selection);
        void clear();
        
        int findSelection(std::string Key);
        
        int getCount();
		
        int getInt(int Selection);
		int getInt(std::string Key);
		float getFloat(int Selection);
		float getFloat(std::string Key);
		std::string getKey(int Selection);
		std::string getValue(int Selection);
		std::string getValue(std::string Key);

		void setError();
		
		void setValue(int Selection,std::string Value);
		void setValue(std::string Key,std::string Value);

		std::vector<std::string> splitStrings(std::string In, std::string Split);
};
///Constructor
fgcom_keyvalue::fgcom_keyvalue(){setError();}

///Checks Selection And Returns An Error If Out Of Bounds
int fgcom_keyvalue::checkSelection(int Selection)
{
	if(Selection < 0 || Selection > getCount())
		return getCount();
	else
		return Selection;
} 


///Return The Amount Of Setting Keys Stored
int fgcom_keyvalue::getCount()
{
	//1 Less Than size() Because Of Error At End
	return keys.size() - 1;
}
		
///Adds A Key And Value;
void fgcom_keyvalue::add(std::string Key, std::string Value)
{
	keys[getCount()] = Key;
	values[getCount()] = Value;
	setError();
}

///Overloaded Adds Another fgcom_keyvalue To This One
void fgcom_keyvalue::add(fgcom_keyvalue KeyValue)
{
	for(int A = 0; A < KeyValue.getCount(); A++)
		add(KeyValue.getKey(A), KeyValue.getValue(A));
}
		
///Returns The Selected Setting Value As An Integer.
int fgcom_keyvalue::getInt(int Selection)
{
	return stoi(values[checkSelection(Selection)]);
}
		
///Returns A Setting Value As An Integer, For A Key Matching The Input.
int fgcom_keyvalue::getInt(std::string Key)
{
    return stoi(values[findSelection(Key)]);
}

///Returns The Selected Setting Value As An float.
float fgcom_keyvalue::getFloat(int Selection)
{
	return stof(values[checkSelection(Selection)]);
}
		
///Returns a setting value as a float, for a key matching the input.
float fgcom_keyvalue::getFloat(std::string Key)
{
    return stof(values[findSelection(Key)]);
}

///Returns The Selected Key As A String
std::string fgcom_keyvalue::getKey(int Selection)
{
	return keys[checkSelection(Selection)];
}
		
///Returns The Selected Setting Value As A String.
std::string fgcom_keyvalue::getValue(int Selection)
{
	return values[checkSelection(Selection)];
}
		
///Returns A Setting Value As A String, For A Key Matching The Input.
std::string fgcom_keyvalue::getValue(std::string Key)
{
	return values[findSelection(Key)];
}


///Pushes An Error To The The End Of Vectors For A Return Value If Nothing Is Found
void fgcom_keyvalue::setError() 
{
	keys.push_back("Error!");
	values.push_back("Error!");
}

///Sets Value For Selection.
void fgcom_keyvalue::setValue(int Selection,std::string Value){
	values[checkSelection(Selection)] = Value;
}
		
///OverLoaded, Uses Key Instead Of Integer Selection
void fgcom_keyvalue::setValue(std::string Key,std::string Value){
	values[findSelection(Key)] = Value;
}
		
		
///Finds Selection By Matching The Input To A Key
int fgcom_keyvalue::findSelection(std::string Key){
	for(int A = 0; A < getCount(); A++){
		if(keys[A] == Key)
			return A;
	}
	//Not Found
	return getCount();
}
		
/**
 * @brief Converts A String Into An Array
 * @param In The String To Be Split
 * @param Split The Value To Split The String At
 * @returns A vector<string>
 */
std::vector<std::string> fgcom_keyvalue::splitStrings(std::string In, std::string Split){
	std::string Hold, Empty;
	std::vector<std::string> OutArray;
	int B = In.length();
	for(int A = 0; A < B; A++){
		if(In[A] == Split[0]){
			OutArray.push_back(Hold);
			Hold = Empty;
			continue;
		}
		Hold += In[A];
	}

	OutArray.push_back(Hold);
	return OutArray;
}
		
///Clears All Internal Data And Shrinks The Storage
void fgcom_keyvalue::clear() {
	keys.clear();
	values.clear();
	values.shrink_to_fit();
	keys.shrink_to_fit();
	setError();
}

#endif
